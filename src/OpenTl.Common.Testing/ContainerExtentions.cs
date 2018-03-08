namespace OpenTl.Common.Testing
{
    using Castle.MicroKernel.Registration;

    using Moq;

    public static class ContainerExtentions
    {
        public static void RegisterType<TService>(this BaseTest baseTest)
            where TService : class
        {
            baseTest.Container.Register(Component.For<TService>().ImplementedBy<TService>().LifestyleSingleton());
        }

        public static void RegisterType<TService, TImpl>(this BaseTest baseTest)
            where TImpl : TService
            where TService : class
        {
            baseTest.Container.Register(Component.For<TService>().ImplementedBy<TImpl>().LifestyleSingleton());
        }

        public static void RegisterInstance<TService, TImpl>(this BaseTest baseTest, TImpl service)
            where TService : class
            where TImpl : TService
        {
            baseTest.Container.Register(Component.For<TService>().Instance(service));
        }

        public static void RegisterInstance<TImpl>(this BaseTest baseTest, TImpl service)
            where TImpl : class 
        {
            baseTest.Container.Register(Component.For<TImpl>().Instance(service));
        }

        public static void RegisterMock<TObject>(this BaseTest baseTest, Mock<TObject> mock)
            where TObject : class
        {
            baseTest.RegisterInstance(mock);
            baseTest.RegisterInstance(mock.Object);
        }

        public static TService Resolve<TService>(this BaseTest baseTest)
        {
            return baseTest.Container.Resolve<TService>();
        }
    }
}